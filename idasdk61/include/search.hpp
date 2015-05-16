/*
 *      Interactive disassembler (IDA).
 *      ALL RIGHTS RESERVED.
 *      Copyright (c) 1990-2008 Hex-Rays
 *
 */

#ifndef __SEARCH_HPP
#define __SEARCH_HPP
#pragma pack(push, 1)   // IDA uses 1 byte alignments!

//--------------------------------------------------------------------------
// Middle-level search functions.
// They all are controlled by the search flags (sflag):

#define SEARCH_UP       0x000           // only one of SEARCH_UP or SEARCH_DOWN can be specified
#define SEARCH_DOWN     0x001
#define SEARCH_NEXT     0x002           // useful only for search() and find_binary()
                                        // for other find_.. functions it is implicitly set
#define SEARCH_CASE     0x004           // case-sensitive search
#define SEARCH_REGEX    0x008           // regular expressions (only for txt search)
#define SEARCH_NOBRK    0x010           // don't test ctrl-break
#define SEARCH_NOSHOW   0x020           // don't display the search progress
#define SEARCH_UNICODE  0x040           // treat strings as unicode
#define SEARCH_IDENT    0x080           // search for an identifier
                                        // it means that the characters before
                                        // and after the pattern can not be is_visible_char()
#define SEARCH_BRK      0x100           // return BADADDR if break is pressed during find_imm()

inline bool search_down(int sflag)      { return (sflag & SEARCH_DOWN) != 0; }

idaman ea_t ida_export find_error(ea_t ea, int sflag, int *opnum=NULL);
idaman ea_t ida_export find_notype(ea_t ea, int sflag, int *opnum=NULL);
idaman ea_t ida_export find_unknown(ea_t ea,int sflag);
idaman ea_t ida_export find_defined(ea_t ea,int sflag);
idaman ea_t ida_export find_void(ea_t ea,int sflag, int *opnum=NULL);
idaman ea_t ida_export find_data(ea_t ea,int sflag);
idaman ea_t ida_export find_code(ea_t ea,int sflag);
idaman ea_t ida_export find_not_func(ea_t ea,int sflag);
idaman ea_t ida_export find_imm(ea_t newEA,int sflag, sval_t srchValue, int *opnum=NULL);
idaman ea_t ida_export find_binary(ea_t startea,
                 ea_t endea,
                 const char *ubinstr,
                 int radix,
                 int sflag);
idaman ea_t ida_export find_text(ea_t startEA, int y, int x, const char *ustr, int sflag);


// Search for a text substring (low level function)
//      ud      -line array parameter
//      start   - pointer to starting place:
//                 start->ea     starting address
//                 start->lnnum  starting Y coordinate
//      end     - pointer to ending place:
//                 end->ea       ending address
//                 end->lnnum    ending Y coordinate
//      startx  - pointer to starting X coordinate
//      str     - substring to search for.
//      sflag   - search control flags. All SEARCH... flags may be used
// Returns:
//      0 - substring not found
//      1 - substring found. The matching position is returned in:
//              start->ea       address
//              start->lnnum    Y coordinate
//              *startx         X coordinate
//      2 - search was cancelled by ctrl-break.
//          The farthest searched address is
//          returned in the same manner as in the successful return (1).
//      3 - the input regular expression is bad.
//          The error message was displayed
//

class place_t;
idaman int ida_export search(
                void *ud,
                place_t *start,
                const place_t *end,
                int *startx,
                const char *str,
                int sflag);


// convert user-specified binary string to internal representation
//      ea - linear address to convert for (the conversion depends on the
//           address, because the number of bits in a byte depend on the
//           segment type)
//      in - input text string. contains space-separated
//              - numbers (numeric base is determined by 'radix')
//                if value of number fits a byte, it is considered as a byte
//                if value of number fits a word, it is considered as 2 bytes
//                if value of number fits a dword,it is considered as 4 bytes
//              - "..." string constants
//              - 'x' character constants
//              - ? question marks (to denote variable bytes)
//      out  - buffer for the output sequence of bytes
//      mask - buffer for the output comparision mask
//             if mask[0] == 0xFF upon return, then there were question marks in
//             the input text string
//      radix - numeric base of numbers (8,10,16)
//      unicode - treat strings as unicode
//                (note: L"string" is another way to enter unicode strings)
// the output buffers are assumed to be MAXSTR bytes
// returns: length of output string
//          -1 if the input string has bad format (warning is displayed)

idaman int ida_export user2bin(
                ea_t ea,
                const char *in,
                uchar *out,
                uchar *mask,
                int radix,
                bool unicode);

#pragma pack(pop)
#endif // __SEARCH_HPP
