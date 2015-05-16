/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _OFFSET_HPP
#define _OFFSET_HPP
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

#include <nalt.hpp>

//      This file contains functions that deal with offsets.
//      "Being an offset" is a characteristic of an operand.
//      This means that operand or its part represent offset from
//      some address in the program. This linear address is called
//      "offset base". Some operands may have 2 offsets simultaneosly.
//      Generally, IDA doesn't handle this except for Motorola outer offsets.
//      Thus there may be two offset values in an operand: simple offset and
//      outer offset.
//
//      Outer offsets are handled by specifying special operand number:
//      it should be ORed with OPND_OUTER value (see bytes.hpp)
//
//      See bytes.hpp for further explanation of operand numbers
//


// Convert operand to offset
//      ea   - linear address
//             if 'ea' has unexplored bytes, try to convert them to
//                              no segment   : fail
//                              16bit segment: to 16bit word data
//                              32bit segment: to dword
//      n    - number of operand (may be ORed with OPND_OUTER)
//              0: first
//              1: second
//              OPND_MASK: both operands
//      base - base of offset (linear address)
// To delete an offset, use noType() function
// returns: 1-ok
//          0-failure
// OBSOLETE FUNCTION, use op_offset() instead

idaman bool ida_export set_offset(ea_t ea, int n, ea_t base);      // returns success


// Convert operand to a reference
//      ea   - linear address
//             if 'ea' has unexplored bytes, try to convert them to
//                              no segment   : fail
//                              16bit segment: to 16bit word data
//                              32bit segment: to dword
//      n    - number of operand (may be ORed with OPND_OUTER)
//              0: first
//              1: second
//              2: third
//              OPND_MASK: all operands
//      ri   - reference information
// To delete an offset, use noType() function
// returns: 1-ok
//          0-failure

idaman int ida_export op_offset_ex(ea_t ea, int n, const refinfo_t *ri);
idaman int ida_export op_offset(ea_t ea, int n, reftype_t type, ea_t target=BADADDR,
                        ea_t base=0, adiff_t tdelta=0);


// Get offset base value
//      ea   - linear address
//      n    - number of operand (may be ORed with OPND_OUTER)
//              0: first
//              1: second
//              OPND_MASK: try to get base of the first operand,
//                         get the second if the first doesn't exist
// returns: offset base or BADADDR
// OBSOLETE FUNCTION, use get_refinfo() instead

idaman ea_t ida_export get_offbase(ea_t ea,int n);              // get offset base


// Get offset expression (in the form "offset name+displ")
// This function returns colored expression.
//      ea      - start of instruction or data with the offset expression
//      n       - number of operand (may be ORed with OPND_OUTER)
//                0: first operand, 1: second operand
//      from    - linear address of instruction operand or data referring to
//                the name. This address will be used to get fixup information,
//                so it should point to exact position of operand in the
//                instruction.
//      offset  - value of operand or its part. The function will return
//                text representation of this value as offset expression.
//      buf     - output buffer to hold offset expression
//      bufsize - size of the output buffer
//      getn_flags - combination of
//                GETN_APPZERO: meaningful only if the name refers to
//                              a structure. appends the struct field name
//                              if the field offset is zero
//                GETN_NODUMMY: do not generate dummy names for the expression
//                              but pretend they already exist
//                              (useful to verify that the offset expression
//                              can be represented)
// This function uses offset translation function (ph.translate) if your IDP
// module have such a function. Translation function is used to map linear
// addresses in the program (only for offsets).
//
// Example: suppose we have instruction at linear address 0x00011000
//              mov     ax, [bx+7422h]
// and at ds:7422h
//      array   dw      ...
// we want to represent the second operand with an offset expression
// then we call
//
//      get_offset_expresion(0x001100, 1, 0x001102, 0x7422, buf);
//      where:               |         |  |         |       |
//                           |         |  |         |       +output buffer
//                           |         |  |         +value of offset expression
//                           |         |  +address offset value in the instruction
//                           |         +the second operand
//                           +address of instruction
// and the function will return a colored string:
//     offset array
// returns:
//      0-can't convert to offset expression
//      1-ok, a simple offset expression
//      2-ok, a complex offset expression


idaman int ida_export get_offset_expression(
                          ea_t ea,
                          int n,
                          ea_t from,
                          adiff_t offset,
                          char *buf,
                          size_t bufsize,
                          int getn_flags=0);


idaman int ida_export get_offset_expr(
                          ea_t ea,
                          int n,
                          refinfo_t &ri,
                          ea_t from,
                          adiff_t offset,
                          char *buf,
                          size_t bufsize,
                          int getn_flags=0);


// Does the specified address contain a valid OFF32 value?
// For symbols in special segments the displacement is not taken into account.
// If yes, then the target address of OFF32 will be returned.
// If not, then BADADDR is returned.

idaman ea_t ida_export can_be_off32(ea_t ea);


// Try to calculate the offset base
// This function takes into account the fixup information, current ds and cs
// values.
// If fails, return BADADDR

ea_t calc_probable_base(ea_t ea, asize_t itemsize, const uval_t *p_off);


// Try to calculate the offset base
// 2 bases are checked: current ds and cs
// If fails, return BADADDR

idaman ea_t ida_export calc_probable_base_by_value(ea_t ea, uval_t off);


// Get default reference type depending on the segment
// Returns one of REF_OFF.. constants

idaman reftype_t ida_export get_default_reftype(ea_t ea);


// calculate the target address of an offset expression
// note: this function may change 'ri' structure.
//       if ri.base is BADADDR, it calculates the offset base address
//    from - the referencing instruction/data address
//    ri   - reference info block from the database
//    opval - operand value (usually op_t.value or op_t.addr)
// Returns: the target address of the reference

idaman ea_t ida_export calc_reference_target(ea_t from, refinfo_t &ri, adiff_t opval);


// calculate the value of the reference base.
// the reference basevalue is used like this:  "offset target - reference_basevalue"
// usually the basevalue is equal to 0
// if it is not equal to 0, then ri.base contains the address of reference_basevalue
// (which is not equal to reference_basevalue for 16-bit programs!)
//    from - the referencing instruction/data address
//    ri   - reference info block from the database
//    opval - operand value (usually op_t.value or op_t.addr)
//    target - the reference target. If BADADDR, it will be calculated auotmatically
// Returns: the reference basevalue

idaman ea_t ida_export calc_reference_basevalue(ea_t from, refinfo_t &ri, adiff_t opval, ea_t target);


// the following function retrieves refinfo_t structure and calculates the target

inline ea_t calc_target(ea_t from, ea_t ea, int n, adiff_t opval)
{
  refinfo_t ri;
  if ( get_refinfo(ea, n, &ri) )
    return calc_reference_target(from, ri, opval);
  return BADADDR;
}


#pragma pack(pop)
#endif  // _OFFSET_HPP
