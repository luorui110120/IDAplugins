/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef FIXUP_HPP
#define FIXUP_HPP

//
//      This file contains functions that deal with fixup information
//      A loader should setup fixup information using set_fixup()
//      function.
//

#include <netnode.hpp>
#include <segment.hpp>
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

// Fixup information structure

struct fixup_data_t
{
  uchar type;                   // fixup type
#define FIXUP_MASK      0xF
#define FIXUP_BYTE      FIXUP_OFF8 // 8-bit offset.
#define FIXUP_OFF8      0       // 8-bit offset.
#define FIXUP_OFF16     1       // 16-bit offset.
#define FIXUP_SEG16     2       // 16-bit base--logical segment base (selector).
#define FIXUP_PTR16     3       // 32-bit long pointer (16-bit base:16-bit
                                // offset).
#define FIXUP_OFF32     4       // 32-bit offset.
#define FIXUP_PTR32     5       // 48-bit pointer (16-bit base:32-bit offset).
#define FIXUP_HI8       6       // high  8 bits of 16bit offset
#define FIXUP_HI16      7       // high 16 bits of 32bit offset
#define FIXUP_LOW8      8       // low   8 bits of 16bit offset
#define FIXUP_LOW16     9       // low  16 bits of 32bit offset
#define FIXUP_VHIGH     0xA     // high ph.high_fixup_bits of 32bit offset
#define FIXUP_VLOW      0xB     // low  ph.high_fixup_bits of 32bit offset
#define FIXUP_OFF64     0xC     // 64-bit offset
//#define FIXUP_          0xD
//#define FIXUP_          0xE
#define FIXUP_CUSTOM    0xF     // fixup it is processed by processor module
//
#define FIXUP_REL       0x10    // fixup is relative to the linear address
                                // specified in the 3d parameter to set_fixup()
#define FIXUP_SELFREL   0x0     // self-relative?
                                //   - disallows the kernel to convert operands
                                //      in the first pass
                                //   - this fixup is used during output
                                // This type of fixups is not used anymore.
                                // Anyway you can use it for commenting purposes
                                // in the loader modules
#define FIXUP_EXTDEF    0x20    // target is a location (otherwise - segment)
                                // Use this bit if the target is a symbol
                                // rather than an offset from the beginning of a segment
#define FIXUP_UNUSED    0x40    // fixup is ignored by IDA
                                //   - disallows the kernel to convert operands
                                //   - this fixup is not used during output
#define FIXUP_CREATED   0x80    // fixup was not present in the input file
#ifdef __EA64__
  sel_t sel;            // target selector
#else
  ushort sel;           // target selector
#endif
  ea_t off;             // target offset
  adiff_t displacement; // target displacement

  inline bool is_custom(void) const { return (type & FIXUP_MASK) == FIXUP_CUSTOM; }
};

idaman netnode ida_export_data fixup_node;

// Set fixup information. You should fill fixup_data_t and call this
// function and the kernel will remember information in the database.
// Use this function if FIXUP_REL bit is clear.
//      source - the fixup source address, i.e. the address modified by the fixup

idaman void ida_export set_fixup(ea_t source, const fixup_data_t *fp);


// Set fixup information. You should fill fixup_data_t and call this
// function and the kernel will remember information in the database.
// Use this function if FIXUP_REL bit is set.

idaman void ida_export set_fixup_ex(ea_t source, fixup_data_t *fd, ea_t offset_base);


// Delete fixup information.

idaman void ida_export del_fixup(ea_t source);


// Get fixup information

idaman bool ida_export get_fixup(ea_t source, fixup_data_t *fd);


// Enumerate addresses with fixup information:

idaman ea_t ida_export get_first_fixup_ea(void);
idaman ea_t ida_export get_next_fixup_ea(ea_t ea);
idaman ea_t ida_export get_prev_fixup_ea(ea_t ea);


// Use fixup information for an address.
//      item_ea  - start address of item to modify
//      fixup_ea - address of fixup record
//      n        - number of operand. may be 0, 1, 2
//      is_macro - is the instruction at 'item_ea' a macro
//                 if yes, then partial fixups (HIGH, LOW) won't be applied
// This function converts item_ea flags to offsets/segments.
// For undefined bytes, you may set item_ea == fixup_ea. In this case this
// function will create an item (byte, word, dword) there.
// Returns:
//      false - no fixup at fixup_ea or it has FIXUP_NOUSED flag
//      true  - ok, the fixup information was applied

bool apply_fixup(ea_t item_ea, ea_t fixup_ea, int n, bool is_macro);


// Get base of fixup for set_offset() function

idaman ea_t ida_export get_fixup_base(ea_t source, const fixup_data_t *fd);


//--------------------------------------------------------------------------
inline ea_t get_fixup_extdef_ea(ea_t source, const fixup_data_t *fd)
{
  return (fd != NULL && (fd->type & FIXUP_EXTDEF) != 0)
        ? get_fixup_base(source, fd) + fd->off
        : BADADDR;
}

//--------------------------------------------------------------------------
inline sel_t get_fixup_segdef_sel(const fixup_data_t *fd)
{
  return (fd != NULL && (fd->type & FIXUP_EXTDEF) == 0)
        ? fd->sel
        : BADSEL;
}

//--------------------------------------------------------------------------
inline ea_t get_fixup_extdef_ea(ea_t ea)
{
  fixup_data_t fd;
  if ( get_fixup(ea, &fd) )
    return get_fixup_extdef_ea(ea, &fd);
  return BADADDR;
}

//--------------------------------------------------------------------------
inline sel_t get_fixup_segdef_sel(ea_t ea)
{
  fixup_data_t fd;
  if ( get_fixup(ea, &fd) )
    return get_fixup_segdef_sel(&fd);
  return BADSEL;
}

// Get FIXUP description comment
// fdp can't be NULL

idaman char *ida_export get_fixup_desc(ea_t source,
                                       fixup_data_t *fdp,
                                       char *buf,
                                       size_t bufsize);


// Does the speficied address range contain any fixup information?

idaman int ida_export contains_fixups(ea_t ea, asize_t size);


// Convert information about the fixup records in the database to
// the new format.

void convert_fixups(void);

// Move fixups when a segment is moved
void move_fixups(ea_t from, ea_t to, asize_t size);

// Relocate the bytes with fixup information once more (generic functon)
// This function may be called from loader_t.move_segm() if it suits the goal
idaman void ida_export gen_fix_fixups(ea_t from, ea_t to, asize_t size);

#pragma pack(pop)
#endif // FIXUP_HPP
