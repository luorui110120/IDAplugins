/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _FRAME_HPP
#define _FRAME_HPP
#include <funcs.hpp>
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

//
//      This file contains routines to manipulate function stack frames, stack
//      variables, register variables and local labels.
//      The frame is represented as a structure:
//
//    +----------------------------------------+
//    | function arguments                     |
//    +----------------------------------------+
//    | return address (isn't stored in func_t)|
//    +----------------------------------------+
//    | saved registers (SI,DI,etc)            |
//    +----------------------------------------+        <- BP
//    | local variables                        |
//    +----------------------------------------+        <- SP
//
//      Also we need to trace value of SP register. For this we introduce
//      an array of SP register change points (stkpnt_t).
//

class struc_t;         // #include <struct.hpp>
class member_t;        // #include <struct.hpp>
class op_t;            // #include <ua.hpp>


// SP register change point:
// This structure is only for the kernel.
// Please use special functions to examine/manipulate the stack pointer.
// They are below in this file (stack pointer change points)

struct stkpnt_t
{
  ea_t ea;              // linear address
  sval_t spd;           // here we keep a cumulative difference from [BP-frsize]
  bool operator < (const stkpnt_t &r) const { return ea < r.ea; }
};


//--------------------------------------------------------------------------
//      F R A M E   M A N I P U L A T I O N
//--------------------------------------------------------------------------

// Function frames are based on structures. In order to access structure
// of a function frame, use pfn->frame as ID of a structure.

// Add function frame.
//      pfn - pointer to function structure
//      frsize  - size of function local variables
//      frregs  - size of saved registers
//      argsize - size of function arguments area which will be purged upon return
//                This parameter is used for __stdcall and __pascal calling conventions
//                For other calling conventions please pass 0
// returns: 1-ok, 0-failed (no function, frame already exists)

idaman bool ida_export add_frame(func_t *pfn,
                                 asize_t frsize,
                                 ushort frregs,
                                 asize_t argsize);


// Delete a function frame
//      pfn - pointer to function structure
// returns: 1-ok, 0-failed

idaman bool ida_export del_frame(func_t *pfn);


// Set size of function frame
//      pfn - pointer to function structure
//      frsize  - size of function local variables
//      frregs  - size of saved registers
//      argsize - size of function arguments
// returns: 1-ok, 0-failed

idaman bool ida_export set_frame_size(func_t *pfn,
                                      asize_t frsize,
                                      ushort frregs,
                                      asize_t argsize);


// Get full size of a function frame
// This function takes into account size of local variables + size of
// saved registers + size of return address + size of function arguments
//      pfn - pointer to function structure, may be NULL
// returns: size of frame in bytes or zero

idaman asize_t ida_export get_frame_size(func_t *pfn);


// Get size of function return address
//      pfn - pointer to function structure, can't be NULL

idaman int ida_export get_frame_retsize(func_t *pfn);


// Get pointer to function frame
//      pfn - pointer to function structure
// returns: pointer to function frame

idaman struc_t *ida_export get_frame(const func_t *pfn);
inline struc_t *get_frame(ea_t ea) { return get_frame(get_func(ea)); }


// Update frame pointer delta
//      pfn - pointer to function structure
//      fpd - new fpd value
// fpd can not be bigger than the local variable area size
// returns: success

idaman bool ida_export update_fpd(func_t *pfn, asize_t fpd);


// Set the number of purged bytes for a function or data item (funcptr)
//      ea - address of the function of item
//      nbytes - number of purged bytes
//      override_old_value - may overwrite old information
//               about purged bytes
// This function will update the database and plan to reanalyze items
// referencing the specified address. It works only for processors
// with PR_PURGING bit in 16 and 32 bit modes.
// returns: success

idaman bool ida_export set_purged(ea_t ea, int nbytes, bool override_old_value);


// Get function by its frame id
//      frame_id - id of the function frame
// Returns: start address of the function or BADADDR
// NOTE: this function works only with databases created by IDA > 5.6

idaman ea_t ida_export get_func_by_frame(tid_t frame_id);


//--------------------------------------------------------------------------
//      S T A C K   V A R I A B L E S
//--------------------------------------------------------------------------

// Get pointer to stack variable
//      x  - reference to instruction operand
//      v  - immediate value in the operand (usually x.addr)
//      actval - actual value used to fetch stack variable
//               this pointer may point to 'v'
// returns: NULL or ptr to stack variable

idaman member_t *ida_export get_stkvar(const op_t &x, sval_t v, sval_t *actval);


// Automatically add stack variable if doesn't exist
//      x    - reference to instruction operand
//      v    - immediate value in the operand (usually x.addr)
//      flags- combination of STKVAR_... constants
// returns: 1-ok
// Processor modules should use ua_stkvar()

idaman bool ida_export add_stkvar3(const op_t &x, sval_t v, int flags);

#define STKVAR_VALID_SIZE       0x0001 // x.dtyp contains correct variable type
                                       // (for insns like 'lea' this bit must be off)
                                       // in general, dr_O references do not allow
                                       // to determine the variable size


// Define/redefine a stack variable
//      pfn - pointer to function
//      name - variable name, NULL means autogenerate a name
//      off - offset of the stack variable in the frame
//            negative values denote local variables, positive - function arguments
//      flags - variable type flags (byteflag() for a byte variable, for example)
//      ti   - additional type information (like offsets, structs, etc)
//      nbytes - number of bytes occupied by the variable
// returns: 1-ok

idaman bool ida_export add_stkvar2(func_t *pfn,
                                   const char *name,
                                   sval_t off,
                                   flags_t flags,
                                   const opinfo_t *ti,
                                   asize_t nbytes);


// Build automatic stack variable name
//      buf - pointer to buffer. must be at least MAXNAMELEN
//      pfn - pointer to function (can't be NULL!)
//      v   - value of variable offset
// returns: ptr to buf

idaman char *ida_export build_stkvar_name(char *buf, size_t bufsize, func_t *pfn, sval_t v);


// internal function: create special part of function frame
// this function won't create zero size members
// also it doesn't check the validity of the "name"
// returns: STRUC_ERROR.. codes (see struct.hpp)

int add_frame_spec_member(struc_t *sptr, const char *name, ea_t offset, asize_t nbytes);


// Delete all stack variables in the specified range
//      ea1 - starting linear address
//      ea2 - ending   linear address

void del_stkvars(ea_t ea1, ea_t ea2);


// Calculate offset of stack variable in the frame structure
//      pfn - pointer to function (can't be NULL!)
//      x   - reference to instruction operand
//      v   - value of variable offset in the instruction
// returns: offset of stack variable in the frame structure (0..n)

ea_t calc_frame_offset(func_t *pfn, const op_t *x, sval_t v);


// Calculate offset of stack variable in the frame structure
//      pfn - pointer to function (can't be NULL!)
//      ea  - linear address of the instruction
//      n   - number of operand: (0..UA_MAXOP-1)
//              -1 - error, return BADADDR
// return BADADDR if some error (issue a warning if stack frame is bad)

idaman ea_t ida_export calc_stkvar_struc_offset(func_t *pfn, ea_t ea, int n);


// Find and delete unreferenced stack variable definitions
//      pfn - pointer to the function
// Returns: number of deleted definitions

idaman int ida_export delete_unreferenced_stkvars(func_t *pfn);


// Find and undefine references to dead stack variables
// (i.e. operands displayed in red)
// These operands will be untyped and most likely displayed in hex.
//      pfn - pointer to the function
// Returns: number of reset operands

idaman int ida_export delete_wrong_stkvar_ops(func_t *pfn);


//--------------------------------------------------------------------------
//      R E G I S T E R   V A R I A B L E S
//--------------------------------------------------------------------------
// A register variable allows the user to rename a general processor register
// to a meaningful name.
// IDA doesn't check whether the target assembler supports the register renaming.
// All register definitions will appear at the beginning of the function.

struct regvar_t : public area_t
{
  char *canon;          // canonical register name (case-insensitive)
  char *user;           // user-defined register name
  char *cmt;            // comment to appear near definition
};

// Define a register variable
//      pfn     - function in which the definition will be created
//      ea1,ea2 - range of addresses within the function where the definition
//                will be used
//      canon   - name of a general register
//      user    - user-defined name for the register
//      cmt     - comment for the definition
// returns: error code REGVAR_ERROR_... (see below)

idaman int ida_export add_regvar(func_t *pfn, ea_t ea1, ea_t ea2,
                        const char *canon,
                        const char *user,
                        const char *cmt);
#define REGVAR_ERROR_OK         0     // all ok
#define REGVAR_ERROR_ARG        (-1)  // function arguments are bad
#define REGVAR_ERROR_RANGE      (-2)  // the definition range is bad
#define REGVAR_ERROR_NAME       (-3)  // the provided name(s) can't be accepted


// Find a register variable definition (powerful version)
//      pfn     - function in question
//      ea1,ea2 - range of addresses to search
//      canon   - name of a general register
//      user    - user-defined name for the register
// One of 'canon' and 'user' should be NULL.
// Returns: NULL-not found, otherwise ptr to regvar_t

idaman regvar_t *ida_export find_regvar(func_t *pfn, ea_t ea1, ea_t ea2, const char *canon, const char *user);


// Find a register variable definition
//      pfn     - function in question
//      ea      - current address
//      canon   - name of a general register
// Returns: NULL-not found, otherwise ptr to regvar_t

inline regvar_t *find_regvar(func_t *pfn, ea_t ea, const char *canon)
{
  return find_regvar(pfn, ea, ea+1, canon, NULL);
}


// Rename a register variable
//      pfn     - function in question
//      v       - variable to rename
//      user    - new user-defined name for the register
// Returns: REGVAR_ERROR_...

idaman int ida_export rename_regvar(func_t *pfn, regvar_t *v, const char *user);


// Set comment for a register variable
//      pfn     - function in question
//      v       - variable to rename
//      cmt     - new comment
// Returns: REGVAR_ERROR_...

idaman int ida_export set_regvar_cmt(func_t *pfn, regvar_t *v, const char *cmt);


// Delete a register variable definition
//      pfn     - function in question
//      ea1,ea2 - range of addresses within the function where the definition
//                holds
//      canon   - name of a general register
//      user    - user-defined name for the register
// Returns: REGVAR_ERROR_...

idaman int ida_export del_regvar(func_t *pfn, ea_t ea1, ea_t ea2, const char *canon);


// These functions are for internal use by the kernel
void read_regvars(func_t *pfn);
bool write_regvars(func_t *pfn);
void del_regvars(ea_t ea);
void free_regvar(regvar_t *v);
bool gen_regvar_defs(func_t *pfn, ea_t ea);

//--------------------------------------------------------------------------
//      L O C A L   L A B E L S
//--------------------------------------------------------------------------
// These are LOW LEVEL FUNCTIONS.
// When possible, they should not be used. Use high level functions from <name.hpp>

struct llabel_t
{
  ea_t ea;
  char *name;
};

// Define/rename/delete a local label
//      pfn     - function in which the definition will be created
//      ea      - linear address of the label
//      name    - name of the label. If NULL or empty string, name will be removed
// returns: success
// THIS IS A LOW LEVEL FUNCTION - use set_name() instead of it!

bool set_llabel(func_t *pfn, ea_t ea, const char *name);


// Get address of a local label
//      pfn     - function in question
//      name    - name of the label
// Returns: BADADDR-not found
// THIS IS A LOW LEVEL FUNCTION - use get_name_ea() instead of it!

ea_t get_llabel_ea(func_t *pfn, const char *name);


// Get local label at the specified address
//      pfn     - function in question
//      ea      - linear address of the label
// Returns: NULL or ptr to the name
// THIS IS A LOW LEVEL FUNCTION - use get_name() instead of it!

const char *get_llabel(func_t *pfn, ea_t ea);


// These functions are for internal use by the kernel
void read_llabels(func_t *pfn);
bool write_llabels(func_t *pfn);
void del_llabels(ea_t ea);
void free_llabel(llabel_t *l);

//--------------------------------------------------------------------------
//      S P   R E G I S T E R   C H A N G E   P O I N T S
//--------------------------------------------------------------------------

// Add automatical SP register change point
//      pfn   - pointer to function. may be NULL.
//      ea    - linear address where SP changes
//              usually this is the end of the instruction which
//              modifies the stack pointer (cmd.ea+cmd.size)
//      delta - difference between old and new values of SP
// returns: 1-ok, 0-failed

idaman bool ida_export add_auto_stkpnt2(func_t *pfn, ea_t ea, sval_t delta);


// Add user-defined SP register change point
//      ea    - linear address where SP changes
//      delta - difference between old and new values of SP
// returns: 1-ok, 0-failed

idaman bool ida_export add_user_stkpnt(ea_t ea, sval_t delta);


// Delete SP register change point
//      pfn   - pointer to function. may be NULL.
//      ea    - linear address
// returns: 1-ok, 0-failed

idaman bool ida_export del_stkpnt(func_t *pfn, ea_t ea);


// Get difference between the initial and current values of ESP
//      pfn   - pointer to function. may be NULL.
//      ea    - linear address
// returns 0 or the difference, usually a negative number

idaman sval_t ida_export get_spd(func_t *pfn, ea_t ea);


// Get modification of SP made at the specified location
//      pfn   - pointer to function. may be NULL.
//      ea    - linear address
// If the specified location doesn't contain a SP change point, return 0
// Otherwise return delta of SP modification

idaman sval_t ida_export get_sp_delta(func_t *pfn, ea_t ea);


// Return the address with the minimal spd (stack pointer delta)
// If there are no SP change points, then return BADADDR.

idaman ea_t ida_export get_min_spd_ea(func_t *pfn);


// Recalculate SP delta for an instruction that stops execution.
// The next instruction is not reached from the current instruction.
// We need to recalculate SP for the next instruction.
//      cur_ea  - linear address of the current instruction
// This function will create a new automatic SP register change
// point if nesessary. It should be called from the emulator (emu.cpp)
// when auto_state == AU_USED if the current instruction doesn't pass
// the execution flow to the next instruction.
// returns: 1 - new stkpnt is added, 0 - nothing is changed

idaman bool ida_export recalc_spd(ea_t cur_ea);


#ifndef NO_OBSOLETE_FUNCS
idaman bool ida_export add_auto_stkpnt(ea_t ea, sval_t delta);
idaman bool ida_export add_stkvar(const op_t &x, sval_t v);
#endif


// Low level functions to work with sp change points. Should not be used
// directly!

stkpnt_t * read_stkpnts(func_t *pfn);
bool write_stkpnts(func_t *pfn);
int del_stkpnts(func_t *pfn, ea_t ea1, ea_t ea2);

bool rename_frame(tid_t frame_id, ea_t ea);

#pragma pack(pop)
#endif // _FRAME_HPP
