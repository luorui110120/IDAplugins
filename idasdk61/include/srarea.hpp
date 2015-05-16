/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _SRAREA_HPP
#define _SRAREA_HPP
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

//
// This file contains function that deal with the segment registers
// If your processor doesn't use segment registers, then these functions
// are of no use for you. However, you should define
// two virtual segment registers - CS and DS (for code segment and
// data segment) and specify their internal numbers in LPH structure.
//

#include <string.h>
#include <area.hpp>
class segment_t;

//-------------------------------------------------------------------------
// The values of the segment registers are kept as address ranges. The segment
// register does not change its address within one address range.
// The processor module finds segment register change points and splits
// segreg_t areas so that a new segreg_t area is started at each segment
// register change point. The kernel deletes segreg_t
// if an instruction is converted back to unexplored bytes. So, we have
// information about a segment register by keeping information about the
// range of addresses where segment registers do not change their values.
//
// Note that each segment has information about the default values of
// the segment registers. This information is used if the value of a segment
// register could not be determined.


// segment register values are kept in area_t class:

class segreg_t : public area_t
{

// private definitions

  sel_t _sRegs[SREG_NUM];
  uchar _tags [SREG_NUM];
#define SR_inherit      1               // the value is inherited from the previous area
#define SR_user         2               // the value is specified by the user
#define SR_auto         3               // the value is determined by IDA
#define SR_autostart    4               // used as SR_auto for segment starting address

public:

// get value of a segment register for the area (range of addresses)
//      n - number of segment register. This number is index to
//          the array of register names (ph.regNames). All segment registers
//          should occupy contiguous register numbers.
// returns: value of register

        sel_t &reg(int n)       { return _sRegs[n-ph.regFirstSreg]; }
  const sel_t &reg(int n) const { return _sRegs[n-ph.regFirstSreg]; }


// get information how the register gets its value
//      n - number of segment register. This number is index to
//          the array of register names (ph.regNames). All segment registers
//          should occupy contiguous register numbers.
// returns:
//      SR_inherit - the register doesn't change its value at the start of
//                   this area. The value was just copied from the previous
//                   area.
//      SR_user    - the user had specified value of the register manually.
//      SR_auto    - IDA calculated value of the segment register.
//      SR_autostart-IDA calculated value of the segment register.

        uchar  &tag(int n)       { return _tags [n-ph.regFirstSreg]; }
  const uchar  &tag(int n) const { return _tags [n-ph.regFirstSreg]; }


// make values of all segment registers undefined

  void undefregs(void)  { memset(_sRegs,0xFF,sizeof(_sRegs)); }


// set values of segment registers
//      Regs - array of segment register values

  void setregs(sel_t Regs[]) { memcpy(_sRegs,Regs,sizeof(_sRegs)); }


// set tag of segment registers
//      v - tag to set

  void settags(uchar v) { memset(_tags,v,sizeof(_tags)); }


};

//-------------------------------------------------------------------------

// Segment register area control block. See area.hpp for explanations.

idaman areacb_t ida_export_data SRareas;

// Helper class to lock a segreg_t pointer so it stays valid
class lock_segreg
{
  const segreg_t *sreg;
public:
  lock_segreg(const segreg_t *_sreg) : sreg(_sreg)
  {
    areacb_t_lock_area(&SRareas, sreg);
  }
  ~lock_segreg(void)
  {
    areacb_t_unlock_area(&SRareas, sreg);
  }
};

// Is a segreg pointer locked?
inline bool is_segreg_locked(const segreg_t *sreg)
{
  return areacb_t_get_area_locks(&SRareas, sreg) > 0;
}

//-------------------------------------------------------------------------

// Get value of a segment register
//      ea - linear address in the program
//      rg - number of the segment register
// returns: BADSEL - value of segment register is unknown
//      otherwise returns value of the segment register
// This function uses segment register area and default segment register
// values stored in the segment structure.

idaman sel_t ida_export getSR(ea_t ea,int rg);


// Set default value of a segment register for a segment
//      sg    - pointer to segment structure
//              if NULL, then set the register for all segments
//      rg    - number of segment register
//      value - its default value. this value will be used by getSR()
//              if value of the register is unknown at the specified address.
// returns: true-success

idaman bool ida_export SetDefaultRegisterValue(segment_t *sg, int rg, sel_t value);


// Create a new segment register area.
// This function is used when the IDP emulator detects that a segment
// register changes its value.
//      ea - linear address where the segment register will
//           have a new value. if ea==BADADDR, nothing to do.
//      rg - the number of the segment register
//      v  - the new value of the segment register. If the value is
//           unknown, you should specify BADSEL
//      tag- the register info tag. see tag() for explanations.
//      silent-if false, display a warning() in the case of failure
// returns: 1-ok,0-failure

idaman bool ida_export splitSRarea1(ea_t ea,
                                    int rg,
                                    sel_t v,
                                    uchar tag,
                                    bool silent=false);


// Set the segment register value at the next instruction
// This function is designed to be called from ph.setsgr
// in order to contain the effect of changing a segment
// register value only until the next instruction.
// It is useful, for example, in the ARM module: the modification
// of the T register does not affect existing instructions later in the code.
//      ea1 - address to start to search for an instruction
//      ea2 - the maximal address
//      reg - the segment register number
//      val - the segment register value

idaman void ida_export set_sreg_at_next_code(ea_t ea1, ea_t ea2, int reg, sel_t value);


// Get pointer to segment register area by linear address
//      ea - any linear address in the program
// returns: NULL or pointer to segment register values structure

inline
segreg_t *getSRarea(ea_t ea) { return (segreg_t *)(SRareas.get_area(ea)); }


// Get pointer to segment register area by its number
//      n - number of area (0..qty()-1)
// returns: NULL or pointer to segment register values structure

inline
segreg_t *getnSRarea(int n) { return (segreg_t *)(SRareas.getn_area(n)); }


// Set default value of DS register for all segments

idaman void ida_export set_default_dataseg(sel_t ds_sel);


//-------------------------------------------------------------------------
// For the kernel only:

int createSRarea(ea_t sEA, ea_t eEA);
int killSRareas(ea_t sEA, ea_t eEA);
int delSRarea(ea_t EA);                   // delete segment regs area
int SRareaStart(ea_t sEA, ea_t newstart); // set new start of srarea
int SRareaEnd(ea_t sEA, ea_t newend);     // set new end of srarea
bool splitSRarea(ea_t sEA);

void SRinit(const char *file);
void SRterm(void);
void SRsave(void);

#pragma pack(pop)
#endif // _SRAREA_HPP
